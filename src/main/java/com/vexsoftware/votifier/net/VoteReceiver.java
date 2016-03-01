/*
 - * Copyright (C) 2012 Vex Software LLC
 - * This file is part of Votifier.
 - *
 - * Votifier is free software: you can redistribute it and/or modify
 - * it under the terms of the GNU General Public License as published by
 - * the Free Software Foundation, either version 3 of the License, or
 - * (at your option) any later version.
 - *
 - * Votifier is distributed in the hope that it will be useful,
 - * but WITHOUT ANY WARRANTY; without even the implied warranty of
 - * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 - * GNU General Public License for more details.
 - *
 - * You should have received a copy of the GNU General Public License
 - * along with Votifier.  If not, see <http://www.gnu.org/licenses/>.
 - */
package com.vexsoftware.votifier.net;

import com.earth2me.essentials.Essentials;
import com.earth2me.essentials.User;
import com.vexsoftware.votifier.Votifier;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.model.VoteListener;
import com.vexsoftware.votifier.model.VotifierEvent;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import org.bukkit.Bukkit;
import org.bukkit.Server;
import org.bukkit.event.Event;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.PluginManager;
import org.bukkit.scheduler.BukkitScheduler;

public class VoteReceiver
        extends Thread {
    private static final Logger LOG = Logger.getLogger("Votifier");
    private final Votifier plugin;
    private final String host;
    private final int port;
    private ServerSocket server;
    private boolean running = true;
    Essentials ess = (Essentials) Bukkit.getServer().getPluginManager().getPlugin("Essentials");
    public VoteReceiver(Votifier plugin, String host, int port) throws Exception {
        this.plugin = plugin;
        this.host = host;
        this.port = port;
        this.initialize();
    }

    private void initialize() throws Exception {
        try {
            this.server = new ServerSocket();
            this.server.bind(new InetSocketAddress(this.host, this.port));
        }
        catch (Exception ex) {
            LOG.log(Level.SEVERE, "Error initializing vote receiver. Please verify that the configured");
            LOG.log(Level.SEVERE, "IP address and port are not already in use. This is a common problem");
            LOG.log(Level.SEVERE, "with hosting services and, if so, you should check with your hosting provider.", ex);
            throw new Exception(ex);
        }
    }

    public void shutdown() {
        this.running = false;
        if (this.server == null) {
            return;
        }
        try {
            this.server.close();
        }
        catch (Exception ex) {
            LOG.log(Level.WARNING, "Unable to shut down vote receiver cleanly.");
        }
    }

    @Override
    public void run() {
        while (this.running) {
            try {
                Socket socket = this.server.accept();
                socket.setSoTimeout(5000);
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                InputStream in = socket.getInputStream();
                writer.write("VOTIFIER " + Votifier.getInstance().getVersion());
                writer.newLine();
                writer.flush();
                byte[] block = new byte[256];
                in.read(block, 0, block.length);
                block = RSA.decrypt(block, Votifier.getInstance().getKeyPair().getPrivate());
                int position = 0;
                String opcode = this.readString(block, position);
                position += opcode.length() + 1;
                if (!opcode.equals("VOTE")) {
                    throw new Exception("Unable to decode RSA");
                }
                String serviceName = this.readString(block, position);
                String username = this.readString(block, position += serviceName.length() + 1);
                String address = this.readString(block, position += username.length() + 1);
                String timeStamp = this.readString(block, position += address.length() + 1);
                User u = ess.getUser(username);
                if (u.getPlayer().hasPlayedBefore() == true || Bukkit.getPlayer((String)username) != null) {
                    final Vote vote = new Vote();
                    vote.setServiceName(serviceName);
                    vote.setUsername(username);
                    vote.setAddress(address);
                    vote.setTimeStamp(timeStamp);
                    if (this.plugin.isDebug()) {
                        LOG.info("Received vote record -> " + vote);
                    }
                    for (VoteListener listener : Votifier.getInstance().getListeners()) {
                        try {
                            listener.voteMade(vote);
                        }
                        catch (Exception ex) {
                            String vlName = listener.getClass().getSimpleName();
                            LOG.log(Level.WARNING, "Exception caught while sending the vote notification to the '" + vlName + "' listener", ex);
                        }
                    }
                    this.plugin.getServer().getScheduler().scheduleSyncDelayedTask((Plugin)this.plugin, new Runnable(){

                        @Override
                        public void run() {
                            Bukkit.getServer().getPluginManager().callEvent((Event)new VotifierEvent(vote));
                        }
                    });
                } else {
                    LOG.log(Level.SEVERE, "invalid vote, user has not played on server before.");
                }
                writer.close();
                in.close();
                socket.close();
            }
            catch (SocketException ex) {
                LOG.log(Level.WARNING, "Protocol error. Ignoring packet - " + ex.getLocalizedMessage());
            }
            catch (BadPaddingException ex) {
                LOG.log(Level.WARNING, "Unable to decrypt vote record. Make sure that that your public key");
                LOG.log(Level.WARNING, "matches the one you gave the server list.", ex);
            }
            catch (Exception ex) {
                LOG.log(Level.WARNING, "Exception caught while receiving a vote notification", ex);
            }
        }
    }

    private String readString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder();
        for (int i = offset; i < data.length && data[i] != 10; ++i) {
            builder.append(data[i]);
        }
        return builder.toString();
    }

}

