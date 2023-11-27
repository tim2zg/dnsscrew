package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
)

type CloudfrontIPS struct {
	CloudfrontGlobalIPList       []string `json:"CLOUDFRONT_GLOBAL_IP_LIST"`
	CloudfrontRegionalEdgeIPList []string `json:"CLOUDFRONT_REGIONAL_EDGE_IP_LIST"`
}

var bunnyCDNIPs = []string{"84.17.46.50", "89.187.188.227", "89.187.165.194", "89.187.188.228", "185.180.14.250", "185.93.1.241", "195.181.163.193", "89.187.162.244", "139.180.134.196", "51.83.238.53", "89.38.96.158", "89.187.162.249", "89.187.162.242", "185.102.217.65", "185.93.1.243", "156.146.40.49", "185.59.220.199", "185.59.220.198", "195.181.166.158", "185.180.12.68", "138.199.24.209", "138.199.24.211", "89.187.169.3", "89.187.169.39", "89.187.169.47", "5.188.120.15", "138.199.24.218", "138.199.24.219", "138.199.46.65", "185.40.106.117", "200.25.45.4", "200.25.57.5", "200.25.11.8", "200.25.53.5", "200.25.13.98", "107.155.21.186", "107.155.27.226", "41.242.2.18", "200.25.62.5", "200.25.38.69", "200.25.42.70", "200.25.36.166", "195.206.229.106", "92.223.88.123", "84.17.46.52", "194.242.11.186", "37.19.203.80", "65.108.101.60", "185.164.35.8", "185.173.226.42", "195.69.143.190", "94.20.154.22", "185.93.1.244", "89.38.224.138", "213.170.143.68", "156.59.145.154", "143.244.49.177", "138.199.46.66", "138.199.37.227", "138.199.37.231", "138.199.37.230", "138.199.37.229", "103.216.222.103", "138.199.46.69", "138.199.46.68", "138.199.46.67", "185.93.1.246", "103.216.222.105", "103.216.222.107", "138.199.37.232", "103.216.222.109", "195.181.163.196", "107.182.163.162", "195.181.163.195", "84.17.46.53", "212.102.40.114", "84.17.46.54", "138.199.40.58", "143.244.38.134", "185.152.64.17", "84.17.59.115", "89.187.165.194", "103.216.222.111", "138.199.15.193", "89.35.237.170", "37.19.216.130", "185.93.1.247", "185.93.3.244", "180.149.231.39", "209.160.96.178", "143.244.49.179", "143.244.49.180", "138.199.9.104", "122.10.251.138", "185.152.66.243", "143.244.49.178", "169.150.221.147", "146.59.68.188", "200.25.18.73", "84.17.63.178", "200.25.32.131", "37.19.207.34", "204.16.244.131", "208.83.234.216", "134.195.197.175", "192.189.65.146", "143.244.45.177", "185.93.1.249", "185.93.1.250", "169.150.215.115", "209.177.87.197", "156.146.56.162", "156.146.56.161", "185.93.2.246", "185.93.2.245", "212.102.50.58", "212.102.40.113", "185.93.2.244", "158.69.123.215", "143.244.50.82", "143.244.50.83", "156.146.56.163", "129.227.9.2", "185.135.85.154", "185.165.170.74", "129.227.217.178", "200.25.69.94", "128.1.52.179", "200.25.16.103", "15.235.54.226", "102.67.138.155", "156.59.126.78", "192.34.87.166", "102.219.177.93", "146.70.80.218", "156.146.43.65", "195.181.163.203", "195.181.163.202", "156.146.56.169", "156.146.56.170", "156.146.56.166", "156.146.56.171", "169.150.207.210", "156.146.56.167", "143.244.50.84", "143.244.50.85", "143.244.50.86", "143.244.50.87", "156.146.56.168", "169.150.207.211", "212.102.50.59", "146.185.248.15", "143.244.50.90", "143.244.50.91", "143.244.50.88", "143.244.50.209", "143.244.50.213", "143.244.50.214", "143.244.49.183", "143.244.50.89", "143.244.50.210", "143.244.50.211", "143.244.50.212", "138.199.4.137", "5.42.206.66", "94.46.175.183", "38.54.2.20", "38.54.4.6", "182.93.93.90", "169.150.207.57", "169.150.207.58", "81.30.157.81", "128.1.104.170", "169.150.207.213", "169.150.207.214", "169.150.207.215", "169.150.207.212", "169.150.219.114", "62.113.194.3", "169.150.202.210", "169.150.242.193", "185.93.1.251", "169.150.207.216", "169.150.207.217", "169.150.238.19", "102.219.126.20", "138.199.36.4", "138.199.36.5", "156.59.67.118", "122.10.251.130", "185.24.11.18", "138.199.36.7", "138.199.36.8", "138.199.36.9", "138.199.36.10", "138.199.36.11", "138.199.37.225", "84.17.46.49", "138.199.4.177", "84.17.37.217", "169.150.225.35", "169.150.225.36", "169.150.225.37", "169.150.225.38", "169.150.225.39", "169.150.225.34", "169.150.236.97", "169.150.236.98", "169.150.236.99", "169.150.236.100", "93.189.63.146", "143.244.56.49", "143.244.56.50", "143.244.56.51", "169.150.247.40", "169.150.247.33", "169.150.247.34", "169.150.247.35", "169.150.247.36", "169.150.247.37", "169.150.247.38", "169.150.247.39", "95.217.227.2", "38.142.94.218", "87.249.137.52", "138.199.46.75", "38.104.169.186", "89.187.162.241", "66.181.163.74", "84.17.38.227", "84.17.38.228", "84.17.38.229", "84.17.38.230", "84.17.38.231", "84.17.38.232", "169.150.225.41", "169.150.225.42", "176.123.9.90", "169.150.249.162", "169.150.249.163", "169.150.249.164", "169.150.249.165", "169.150.249.166", "169.150.249.167", "169.150.249.168", "169.150.249.169", "185.131.64.122", "156.247.205.114", "37.236.234.2", "169.150.252.209", "212.102.46.118", "192.169.120.162", "93.180.217.214", "37.19.203.178", "107.155.47.146", "104.166.144.106", "154.47.16.177", "193.201.190.174", "156.59.95.218", "213.170.143.139", "129.227.186.154", "195.238.127.98", "5.189.202.62", "128.1.59.74", "200.25.22.6", "204.16.244.92", "200.25.70.101", "200.25.66.100", "139.180.209.182", "103.108.231.41", "103.108.229.5", "103.216.220.9", "103.75.11.45", "116.202.155.146", "116.202.193.178", "116.202.224.168", "188.40.126.227", "88.99.26.189", "168.119.39.238", "88.99.26.97", "168.119.12.188", "199.247.1.226", "169.197.143.195", "176.9.139.55", "176.9.139.94", "5.161.66.71", "142.132.223.79", "142.132.223.80", "142.132.223.81", "5.161.88.97", "5.161.90.228", "5.161.85.161", "5.161.78.181", "5.161.84.169", "5.161.92.86", "5.161.92.85", "5.161.92.84", "5.161.72.83", "5.161.70.244", "5.161.71.198", "5.161.49.93", "5.161.72.89", "5.161.72.135", "5.161.72.194", "5.161.72.200", "5.161.70.230", "5.161.60.80", "104.237.58.186", "143.244.50.81", "143.244.51.75", "46.4.116.17", "46.4.119.81", "167.235.114.167", "159.69.68.171", "178.63.21.52", "46.4.120.152", "116.202.80.247", "5.9.71.119", "195.201.11.156", "78.46.123.17", "143.244.50.153", "143.244.50.154", "138.199.9.99", "138.199.9.98", "143.244.50.155", "46.4.113.143", "109.248.43.116", "109.248.43.117", "109.248.43.162", "109.248.43.163", "109.248.43.164", "109.248.43.165", "49.12.71.27", "49.12.0.158", "78.47.94.156", "109.248.43.159", "109.248.43.160", "109.248.43.208", "109.248.43.179", "109.248.43.232", "109.248.43.231", "109.248.43.241", "109.248.43.236", "109.248.43.240", "116.202.118.194", "116.202.80.29", "159.69.57.80", "139.180.129.216", "139.99.174.7", "89.187.169.18", "89.187.162.166", "89.187.162.245", "185.180.13.241", "185.59.220.203", "185.59.220.200", "185.59.220.202", "185.59.220.201", "143.244.63.120", "138.199.9.97", "138.199.40.49", "138.199.40.50", "138.199.40.51", "138.199.9.105", "143.244.38.133", "37.19.222.241", "143.244.49.181", "37.19.222.242", "89.187.179.7", "143.244.51.70", "143.244.51.71", "143.244.51.69", "143.244.62.213", "143.244.51.74", "185.93.3.246", "195.181.163.198", "185.152.64.19", "84.17.37.211", "212.102.50.54", "138.199.4.133", "138.199.4.132", "212.102.46.115", "84.17.35.199", "143.244.38.135", "84.17.35.218", "89.187.185.21", "169.150.238.21", "169.150.238.22", "169.150.207.51", "169.150.207.49", "84.17.38.226", "84.17.38.225", "169.150.247.43", "169.150.247.134", "169.150.247.136", "169.150.247.131", "169.150.247.130", "169.150.247.132", "169.150.247.133", "169.150.247.135", "169.150.247.137"}

var StackPathIPs = []string{"64.145.80.0/20", "151.139.32.0/24", "151.139.1.0/24", "72.20.4.0/22", "151.139.78.0/23", "94.46.144.0/24", "69.197.30.0/24", "94.46.149.0/24", "69.16.190.0/23", "69.16.163.0/24", "151.139.204.0/23", "185.69.88.0/23", "151.139.38.0/24", "151.139.48.0/22", "64.145.64.0/20", "151.139.76.0/23", "205.185.215.0/24", "151.139.120.0/23", "151.139.2.0/24", "151.139.187.0/24", "209.197.11.0/24", "69.197.26.0/24", "69.197.35.0/24", "94.46.155.0/24", "151.139.92.0/23", "69.197.10.0/24", "103.66.30.0/24", "69.197.13.0/24", "209.234.246.0/24", "69.197.15.0/24", "151.139.191.0/24", "98.190.66.0/23", "151.139.6.0/24", "151.139.7.0/24", "173.245.196.0/23", "69.16.186.0/24", "98.190.94.0/23", "209.197.6.0/24", "151.139.126.0/23", "69.197.5.0/24", "151.139.20.0/23", "69.197.28.0/24", "184.176.184.0/23", "151.139.28.0/22", "151.139.112.0/24", "151.139.23.0/24", "69.197.20.0/24", "151.139.72.0/22", "103.228.105.0/24", "69.197.62.0/23", "69.197.42.0/24", "209.197.10.0/23", "151.139.216.0/22", "209.197.30.0/23", "209.234.248.0/21", "69.16.184.0/24", "151.139.96.0/23", "216.151.182.0/24", "98.190.74.0/23", "81.171.106.0/24", "209.197.13.0/24", "69.197.29.0/24", "81.171.105.0/24", "69.197.18.0/24", "151.139.21.0/24", "81.171.116.0/24", "69.197.43.0/24", "69.197.16.0/24", "151.139.183.0/24", "209.107.208.0/20", "98.190.78.0/23", "69.197.45.0/24", "94.46.152.0/24", "184.179.88.0/23", "103.228.104.0/24", "216.151.176.0/24", "151.139.94.0/23", "72.20.0.0/22", "69.197.12.0/24", "81.171.68.0/24", "151.139.33.0/24", "151.139.8.128/27", "173.245.218.0/24", "151.139.19.128/25", "69.16.133.0/24", "69.16.143.0/24", "151.139.116.0/23", "151.139.39.0/24", "209.234.240.0/21", "69.197.23.0/24", "151.139.3.0/24", "69.197.27.0/24", "151.139.180.0/24", "69.197.48.0/24", "69.197.19.0/24", "173.245.208.0/20", "151.139.44.0/22", "151.139.12.0/23", "151.139.100.0/24", "151.139.18.0/24", "72.20.16.0/22", "151.139.181.0/24", "151.139.125.0/24", "69.16.138.0/23", "151.139.64.0/23", "72.20.32.0/22", "151.139.54.0/24", "98.190.80.0/23", "151.139.35.0/24", "151.139.176.0/24", "151.139.52.0/22", "151.139.5.0/24", "98.190.72.0/23", "209.107.192.0/20", "185.85.198.0/24", "69.197.47.0/24", "209.197.26.0/24", "69.197.24.0/24", "151.139.90.0/23", "151.139.88.0/23", "98.190.86.0/23", "173.245.192.0/20", "216.151.176.0/21", "151.139.25.0/24", "151.139.186.0/24", "173.245.215.0/24", "209.197.12.0/24", "69.197.8.0/24", "72.20.28.0/22", "108.161.177.0/24", "205.185.206.0/24", "69.197.52.0/22", "69.197.9.0/24", "151.139.37.0/24", "151.139.185.0/24", "69.197.31.0/24", "151.139.19.0/24", "69.16.140.0/24", "151.139.66.0/23", "209.197.28.0/24", "151.139.24.0/24", "151.139.80.0/22", "151.139.118.0/23", "69.197.21.0/24", "173.245.208.0/24", "151.139.26.0/23", "185.69.90.0/23", "69.197.32.0/23", "185.85.196.0/24", "69.197.44.0/24", "98.190.68.0/23", "69.197.4.0/24", "151.139.8.0/24", "98.190.76.0/23", "209.197.4.0/24", "69.197.14.0/24", "151.139.15.0/24", "209.234.242.0/24", "69.16.187.0/24", "205.185.198.0/24", "69.197.46.0/24", "151.139.40.0/22", "69.16.132.0/24", "151.139.232.0/23", "209.197.18.0/24", "103.66.28.0/24", "151.139.122.0/23", "185.85.197.0/24", "173.245.216.0/24", "69.197.17.0/24", "151.139.58.0/23", "173.245.210.0/24", "151.139.11.0/24", "94.46.145.0/24", "69.197.3.0/24", "209.197.8.0/23", "69.197.36.0/23", "69.197.7.0/24", "69.197.1.0/24", "72.20.8.0/22", "69.197.2.0/24", "151.139.189.0/24", "151.139.68.0/22", "151.139.190.0/24", "151.139.114.0/23", "209.197.0.0/23", "94.46.154.0/24", "151.139.9.0/24", "69.197.49.0/24", "151.139.0.0/24", "151.139.124.0/24", "151.139.36.0/24", "69.197.50.0/23", "146.88.130.0/24", "81.171.70.64/26", "151.139.98.0/23", "98.181.86.0/23", "151.139.184.0/24", "69.197.40.0/23", "205.185.219.0/24", "151.139.4.0/24", "216.151.184.0/21", "108.161.176.0/24", "151.139.13.0/24", "151.139.188.0/24", "209.197.14.0/23", "94.46.148.0/24", "98.190.70.0/23", "151.139.208.0/22", "151.139.84.0/22", "151.139.56.0/24", "205.185.217.0/24", "209.197.20.0/23", "94.46.153.0/24", "69.197.11.0/24", "98.190.64.0/23", "81.171.70.0/23", "103.66.29.0/24", "72.20.24.0/22", "151.139.177.0/24", "81.171.61.0/24", "69.197.25.0/24", "69.197.56.0/22", "69.197.38.0/23", "69.16.152.0/24", "209.234.240.0/23", "151.139.14.0/24", "69.197.22.0/24", "69.197.6.0/24", "209.197.27.0/24", "98.190.90.0/23", "151.139.16.0/24", "151.139.34.0/24", "151.139.60.0/22", "74.209.135.0/24", "94.46.150.0/24", "94.46.151.0/24", "151.139.57.0/24", "209.197.16.0/24", "151.139.10.0/24", "185.85.199.0/24", "138.122.232.0/22", "205.185.212.0/24", "209.197.24.0/23", "209.197.29.0/24", "205.185.197.0/24", "74.209.134.0/24", "64.145.64.0/24", "69.16.175.0/24", "69.16.174.0/24", "151.139.130.0/24", "205.185.216.0/24", "98.184.12.0/24", "209.197.2.0/24", "151.139.254.0/24", "209.197.3.0/24", "151.139.255.0/24", "151.139.128.0/24", "205.185.208.0/24"}

var EdgeIo = []string{"152.195.112.0/24", "152.195.248.0/24", "152.195.95.0/24", "152.199.113.0/24", "152.195.230.0/24", "152.199.121.0/24", "152.195.133.0/24", "152.199.38.0/24", "64.12.72.0/24", "64.12.164.0/24", "152.199.3.0/24", "152.195.9.0/24", "152.199.108.0/24", "152.195.242.0/24", "192.16.50.0/24", "152.199.36.0/24", "72.21.88.0/24", "152.195.111.0/24", "152.195.127.0/24", "152.195.88.0/24", "152.195.151.0/24", "152.195.110.0/24", "192.229.209.0/24", "152.195.238.0/24", "152.195.240.0/24", "192.229.134.0/24", "198.7.16.0/24", "192.16.33.0/24", "152.195.59.0/24", "192.16.37.0/24", "64.12.177.0/24", "192.229.243.0/24", "192.229.140.0/24", "152.199.22.0/24", "68.232.46.0/24", "152.195.231.0/24", "192.229.225.0/24", "152.195.134.0/24", "152.195.212.0/24", "152.199.32.0/24", "64.12.166.0/24", "152.195.235.0/24", "152.195.152.0/24", "152.195.183.0/24", "192.229.234.0/24", "192.229.233.0/24", "64.12.75.0/24", "93.184.223.0/24", "152.195.78.0/24", "192.229.136.0/24", "192.229.250.0/24", "152.195.215.0/24", "64.12.172.0/24", "152.195.35.0/24", "64.12.161.0/24", "192.229.141.0/24", "192.229.208.0/24", "68.232.47.0/24", "152.195.56.0/24", "64.12.152.0/24", "152.195.68.0/24", "152.199.2.0/24", "152.195.147.0/24", "5.104.67.0/24", "64.12.137.0/24", "192.16.18.0/24", "5.104.66.0/24", "152.195.179.0/24", "152.195.203.0/24", "152.199.155.0/24", "192.16.22.0/24", "192.229.246.0/24", "192.16.38.0/24", "64.12.132.0/24", "152.195.130.0/24", "72.21.87.0/24", "152.195.62.0/24", "152.199.54.0/24", "192.229.163.0/24", "152.195.214.0/24", "152.199.102.0/24", "152.199.191.0/24", "152.195.213.0/24", "192.229.162.0/24", "152.195.245.0/24", "192.229.248.0/24", "136.228.144.0/24", "192.229.137.0/24", "152.195.74.0/24", "152.195.209.0/24", "152.195.81.0/24", "152.195.148.0/24", "152.199.43.0/24", "192.229.156.0/24", "152.199.114.0/24", "152.199.97.0/24", "152.195.104.0/24", "72.21.89.0/24", "152.199.53.0/24", "192.229.242.0/24", "192.229.132.0/24", "192.16.25.0/24", "110.232.179.0/24", "152.199.37.0/24", "152.195.97.0/24", "152.195.51.0/24", "152.195.106.0/24", "192.16.51.0/24", "152.195.241.0/24", "152.195.82.0/24", "152.195.86.0/24", "152.195.101.0/24", "152.199.34.0/24", "64.12.66.0/24", "152.195.187.0/24", "152.195.146.0/24", "152.195.38.0/24", "152.195.117.0/24", "152.199.105.0/24", "72.21.86.0/24", "152.199.110.0/24", "152.195.65.0/24", "192.229.130.0/24", "192.229.239.0/24", "192.16.34.0/24", "64.12.65.0/24", "64.12.68.0/24", "192.16.15.0/24", "192.229.202.0/24", "64.12.159.0/24", "64.12.147.0/24", "152.195.92.0/24", "152.199.16.0/24", "152.199.118.0/24", "192.16.49.0/24", "192.16.7.0/24", "152.195.113.0/24", "68.232.42.0/24", "108.161.247.0/24", "110.232.178.0/24", "152.195.26.0/24", "152.199.0.0/24", "64.12.180.0/24", "192.229.149.0/24", "192.229.189.0/24", "192.16.48.0/24", "192.16.14.0/24", "198.7.29.0/24", "152.195.249.0/24", "152.195.121.0/24", "64.12.255.0/24", "152.195.196.0/24", "152.199.6.0/24", "152.199.20.0/24", "64.12.154.0/24", "192.16.32.0/24", "192.229.135.0/24", "152.195.188.0/24", "192.229.232.0/24", "152.195.90.0/24", "192.16.19.0/24", "152.195.100.0/24", "152.195.14.0/24", "68.232.34.0/24", "152.195.123.0/24", "192.229.146.0/24", "64.12.169.0/24", "152.195.34.0/24", "117.18.239.0/24", "198.7.19.0/24", "192.229.194.0/24", "192.229.153.0/24", "110.232.176.0/24", "46.22.67.0/24", "152.195.36.0/24", "152.199.124.0/24", "93.184.221.0/24", "152.195.69.0/24", "152.195.155.0/24", "152.195.164.0/24", "192.229.131.0/24", "152.195.167.0/24", "152.195.202.0/24", "152.199.19.0/24", "192.16.55.0/24", "152.199.91.0/24", "152.195.137.0/24", "192.16.58.0/24", "192.229.247.0/24", "64.12.157.0/24", "152.195.116.0/24", "117.18.232.0/24", "192.229.251.0/24", "152.195.236.0/24", "152.195.253.0/24", "64.12.48.0/24", "64.12.139.0/24", "64.12.170.0/24", "72.21.81.0/24", "64.12.175.0/24", "64.12.158.0/24", "192.229.129.0/24", "152.195.83.0/24", "192.229.224.0/24", "64.12.131.0/24", "152.195.221.0/24", "152.195.150.0/24", "152.199.109.0/24", "152.195.85.0/24", "152.195.131.0/24", "152.199.112.0/24", "152.199.24.0/24", "152.195.25.0/24", "46.22.68.0/24", "152.195.13.0/24", "192.229.133.0/24", "5.104.64.0/24", "152.195.63.0/24", "46.22.72.0/24", "64.12.0.0/24", "152.199.122.0/24", "72.21.92.0/24", "192.16.46.0/24", "64.12.130.0/24", "152.195.28.0/24", "108.161.253.0/24", "152.199.51.0/24", "192.229.255.0/24", "192.229.150.0/24", "68.232.45.0/24", "93.184.219.0/24", "152.195.8.0/24", "64.12.64.0/24", "93.184.220.0/24", "64.12.153.0/24", "93.184.222.0/24", "152.195.75.0/24", "152.195.128.0/24", "152.199.127.0/24", "152.195.64.0/24", "152.195.189.0/24", "108.161.254.0/24", "192.16.24.0/24", "93.184.215.0/24", "192.229.222.0/24", "198.7.22.0/24", "152.199.35.0/24", "152.199.100.0/24", "64.12.141.0/24", "152.195.53.0/24", "46.22.77.0/24", "152.195.98.0/24", "192.229.144.0/24", "152.195.18.0/24", "192.16.52.0/24", "152.195.250.0/24", "46.22.74.0/24", "152.195.255.0/24", "64.12.135.0/24", "152.199.120.0/24", "152.195.32.0/24", "64.12.150.0/24", "64.12.178.0/24", "152.199.49.0/24", "152.195.204.0/24", "152.195.89.0/24", "192.16.59.0/24", "152.195.145.0/24", "192.229.236.0/24", "117.18.237.0/24", "152.195.91.0/24", "152.195.247.0/24", "192.30.25.0/24", "68.232.44.0/24", "192.229.227.0/24", "152.195.57.0/24", "152.199.55.0/24", "192.229.178.0/24", "152.195.244.0/24", "64.12.168.0/24", "152.195.135.0/24", "192.229.128.0/24", "68.232.35.0/24", "152.199.50.0/24", "192.229.154.0/24", "152.195.50.0/24", "152.195.237.0/24", "64.12.67.0/24", "152.195.19.0/24", "152.199.104.0/24", "192.229.198.0/24", "64.12.148.0/24", "192.229.219.0/24", "152.199.52.0/24", "64.12.155.0/24", "192.229.213.0/24", "192.229.138.0/24", "64.12.16.0/24", "152.195.182.0/24", "64.12.171.0/24", "152.195.76.0/24", "152.199.33.0/24", "192.229.210.0/24", "152.195.197.0/24", "192.229.220.0/24", "192.229.169.0/24", "72.21.91.0/24", "152.195.156.0/24", "152.195.122.0/24", "152.195.15.0/24", "192.229.238.0/24", "64.12.160.0/24", "152.199.5.0/24", "192.229.145.0/24", "192.229.223.0/24", "152.195.243.0/24", "192.229.170.0/24", "152.199.119.0/24", "152.195.12.0/24", "198.7.27.0/24", "68.232.32.0/24", "192.16.23.0/24", "152.195.6.0/24", "64.12.144.0/24", "152.195.251.0/24", "64.12.136.0/24", "152.195.129.0/24", "68.232.33.0/24", "46.22.73.0/24", "152.199.44.0/24", "152.199.126.0/24", "192.229.221.0/24", "72.21.85.0/24", "152.199.111.0/24", "152.199.96.0/24", "64.12.176.0/24", "64.12.138.0/24", "152.195.166.0/24", "192.16.36.0/24", "64.12.133.0/24", "152.199.90.0/24", "152.195.79.0/24", "152.195.29.0/24", "152.195.84.0/24", "152.199.117.0/24", "68.232.37.0/24", "64.12.165.0/24", "110.164.36.0/24", "152.199.41.0/24", "152.195.103.0/24", "192.16.53.0/24", "152.199.123.0/24", "152.195.94.0/24", "64.12.156.0/24", "192.229.253.0/24", "152.199.56.0/24", "152.195.67.0/24", "152.195.205.0/24", "64.12.146.0/24", "152.195.58.0/24", "192.16.56.0/24", "64.12.145.0/24", "152.195.144.0/24", "152.195.55.0/24", "192.229.179.0/24", "192.229.252.0/24", "152.195.70.0/24", "192.16.60.0/24", "152.195.119.0/24", "152.195.157.0/24", "152.195.87.0/24", "213.175.80.0/24", "152.195.141.0/24", "5.104.68.0/24", "152.195.184.0/24", "152.199.115.0/24", "192.229.142.0/24", "152.199.39.0/24", "152.195.105.0/24", "198.7.17.0/24", "192.229.190.0/24", "152.199.116.0/24", "192.229.171.0/24", "152.195.125.0/24", "192.229.173.0/24", "152.195.109.0/24", "152.195.71.0/24", "152.199.40.0/24", "152.195.219.0/24", "152.195.80.0/24", "152.195.93.0/24", "198.7.20.0/24", "64.12.32.0/24", "152.199.23.0/24", "93.184.216.0/24", "192.30.24.0/24", "152.195.228.0/24", "108.161.240.0/24", "192.229.254.0/24", "152.195.126.0/24", "152.199.98.0/24", "152.195.118.0/24", "68.232.39.0/24", "72.21.80.0/24", "192.229.182.0/24", "192.229.151.0/24", "152.195.246.0/24", "152.195.4.0/24", "152.195.115.0/24", "152.195.181.0/24", "152.195.211.0/24", "152.199.107.0/24", "152.199.18.0/24", "152.195.107.0/24", "108.161.245.0/24", "152.195.99.0/24", "152.199.1.0/24", "192.16.54.0/24", "152.195.233.0/24", "152.195.220.0/24", "152.195.72.0/24", "152.195.124.0/24", "152.195.232.0/24", "152.195.96.0/24", "152.195.16.0/24", "152.195.33.0/24", "64.12.140.0/24", "152.195.207.0/24", "68.232.38.0/24", "192.16.16.0/24", "152.195.208.0/24", "152.195.234.0/24", "68.232.36.0/24", "64.12.143.0/24", "192.229.155.0/24", "64.12.151.0/24", "152.195.102.0/24", "192.229.231.0/24", "152.195.154.0/24", "152.195.239.0/24", "64.12.173.0/24", "192.229.157.0/24", "198.7.18.0/24", "152.199.93.0/24", "152.195.60.0/24", "152.195.11.0/24", "192.16.6.0/24", "192.229.211.0/24", "192.16.35.0/24", "64.12.70.0/24", "72.21.95.0/24", "152.195.52.0/24", "152.195.77.0/24", "152.195.199.0/24", "152.195.17.0/24", "152.195.54.0/24", "152.199.42.0/24", "192.229.237.0/24", "46.22.71.0/24", "152.195.136.0/24", "152.195.37.0/24", "192.229.139.0/24", "152.199.101.0/24", "192.229.249.0/24", "152.199.4.0/24", "152.195.198.0/24", "64.12.71.0/24", "64.12.174.0/24", "152.199.99.0/24", "192.229.218.0/24", "152.195.140.0/24", "72.21.90.0/24", "192.229.152.0/24", "49.231.126.0/24", "152.195.66.0/24", "108.161.241.0/24", "152.195.186.0/24", "152.195.39.0/24", "46.22.66.0/24", "64.12.69.0/24", "152.195.149.0/24", "152.195.61.0/24", "119.46.85.0/24", "152.195.206.0/24", "152.199.125.0/24", "152.195.229.0/24", "192.16.42.0/24", "117.18.238.0/24", "152.195.114.0/24", "192.16.43.0/24", "46.22.76.0/24", "152.199.17.0/24", "152.195.108.0/24", "152.199.48.0/24", "152.195.73.0/24", "152.195.22.0/24", "152.195.252.0/24", "46.22.70.0/24", "152.199.21.0/24", "152.195.210.0/24", "152.199.103.0/24", "152.195.254.0/24", "152.195.153.0/24", "152.195.139.0/24", "152.195.120.0/24", "64.12.179.0/24", "152.195.138.0/24", "192.16.63.0/24", "152.195.132.0/24"}

var EdgeIo2 = []string{"69.28.128.0/18", "178.79.192.0/18", "64.12.224.0/21", "69.164.5.0/24", "69.28.147.0/24", "111.119.0.0/22", "206.223.120.0/24", "208.111.136.0/24", "69.28.145.0/24", "216.247.121.0/24", "68.142.74.0/24", "208.111.180.0/22", "203.9.177.0/24", "203.9.178.0/24", "69.164.24.0/22", "46.228.144.0/20", "69.164.60.0/24", "178.249.108.0/24", "68.142.82.0/24", "68.142.72.0/23", "69.164.32.0/23", "208.111.131.0/24", "178.249.105.0/24", "178.79.220.0/23", "208.111.154.0/24", "208.111.128.0/18", "69.28.168.0/24", "208.111.188.0/22", "178.79.240.0/21", "46.228.147.0/24", "87.248.223.0/24", "111.119.4.0/22", "68.142.126.0/23", "69.164.22.0/23", "178.79.232.0/22", "203.9.176.0/21", "216.247.120.0/24", "68.142.123.0/24", "117.121.248.0/22", "185.178.52.0/22", "46.183.88.0/21", "69.164.47.0/24", "69.164.52.0/24", "95.140.224.0/22", "69.164.58.0/24", "111.119.24.0/21", "87.248.214.0/24", "69.28.131.0/24", "87.248.221.0/24", "208.111.157.0/24", "69.164.19.0/24", "111.119.11.0/24", "178.79.228.0/23", "111.119.16.0/23", "69.28.177.0/24", "69.164.0.0/18", "69.28.134.0/24", "208.69.176.0/21", "46.228.149.0/24", "68.142.68.0/22", "41.63.64.0/22", "68.142.64.0/18", "41.63.64.0/18", "208.69.180.0/24", "208.111.163.0/24", "68.142.100.0/24", "46.228.150.0/24", "111.119.7.0/24", "69.28.180.0/24", "68.142.75.0/24", "117.121.254.0/23", "69.28.169.0/24", "87.248.212.0/23", "208.69.179.0/24", "46.228.146.0/24", "178.79.226.0/23", "69.28.143.0/24", "69.164.17.0/24", "111.119.3.0/24", "178.249.104.0/21", "208.111.186.0/23", "69.164.28.0/22", "208.69.183.0/24", "69.28.161.0/24", "46.228.145.0/24", "69.28.190.0/23", "203.77.188.0/23", "69.164.46.0/24", "41.63.99.0/24", "69.28.170.0/24", "46.228.148.0/24", "185.116.100.0/22", "203.77.188.0/22", "178.249.110.0/24", "69.28.174.0/23", "178.79.214.0/23", "208.69.181.0/24", "69.164.4.0/24", "178.79.203.0/24", "203.77.184.0/22", "208.69.177.0/24", "68.142.91.0/24", "208.111.177.0/24", "41.63.96.0/23", "95.140.224.0/20", "68.142.115.0/24", "111.119.22.0/23", "69.28.139.0/24", "87.248.192.0/19", "117.121.248.0/23", "208.69.178.0/24", "68.142.77.0/24", "111.119.20.0/23", "64.12.232.0/21", "69.164.6.0/23", "69.164.40.0/23", "208.69.182.0/24", "69.28.142.0/24", "208.111.146.0/24", "208.111.184.0/24", "95.140.237.0/24", "208.111.172.0/24", "69.164.0.0/24", "117.121.248.0/21", "208.111.152.0/23", "216.247.123.0/24", "178.79.248.0/21", "117.121.250.0/23", "178.79.236.0/22", "178.79.230.0/23", "178.249.106.0/24", "87.248.210.0/23"}

var gitHubIPS *net.IPNet
var sucuri []*net.IPNet
var stackPath []*net.IPNet
var bunnyCDN []net.IP
var cloudFront []*net.IPNet
var fastly []*net.IPNet
var cloudflare []*net.IPNet
var edgeIo []*net.IPNet

func loadIPRanges() {
	// Load the IP ranges
	fmt.Println("Loading IP ranges")
	var cloudfrontIPS = loadCloudFrontIPs()
	for _, ipRange := range cloudfrontIPS.CloudfrontGlobalIPList {
		_, ipNet, _ := net.ParseCIDR(ipRange)
		cloudFront = append(cloudFront, ipNet)
	}
	for _, ipRange := range cloudfrontIPS.CloudfrontRegionalEdgeIPList {
		_, ipNet, _ := net.ParseCIDR(ipRange)
		cloudFront = append(cloudFront, ipNet)
	}

	_, gitHubIPS, _ = net.ParseCIDR("185.199.108.0/24")
	_, range1, _ := net.ParseCIDR("208.109.1.0/24")
	_, range2, _ := net.ParseCIDR("66.248.202.0/24")
	_, range3, _ := net.ParseCIDR("185.93.231.0/24")
	_, range4, _ := net.ParseCIDR("208.109.0.0/24")
	_, range5, _ := net.ParseCIDR("193.19.225.0/24")
	_, range6, _ := net.ParseCIDR("185.93.229.0/24")
	_, range7, _ := net.ParseCIDR("192.124.249.0/24")
	_, range8, _ := net.ParseCIDR("192.88.135.0/24")
	_, range9, _ := net.ParseCIDR("185.93.228.0/24")
	_, range10, _ := net.ParseCIDR("192.88.134.0/24")
	_, range11, _ := net.ParseCIDR("66.248.200.0/24")
	_, range12, _ := net.ParseCIDR("192.161.0.0/24")
	_, range13, _ := net.ParseCIDR("66.248.201.0/24")
	_, range14, _ := net.ParseCIDR("66.248.203.0/24")
	_, range15, _ := net.ParseCIDR("185.93.230.0/24")

	sucuri = append(sucuri, range1)
	sucuri = append(sucuri, range2)
	sucuri = append(sucuri, range3)
	sucuri = append(sucuri, range4)
	sucuri = append(sucuri, range5)
	sucuri = append(sucuri, range6)
	sucuri = append(sucuri, range7)
	sucuri = append(sucuri, range8)
	sucuri = append(sucuri, range9)
	sucuri = append(sucuri, range10)
	sucuri = append(sucuri, range11)
	sucuri = append(sucuri, range12)
	sucuri = append(sucuri, range13)
	sucuri = append(sucuri, range14)
	sucuri = append(sucuri, range15)

	for _, StackPath := range StackPathIPs {
		_, ipNet, _ := net.ParseCIDR(StackPath)
		stackPath = append(stackPath, ipNet)
	}

	for _, ipNetLul := range EdgeIo {
		_, ipNet, _ := net.ParseCIDR(ipNetLul)
		edgeIo = append(edgeIo, ipNet)
	}

	for _, ipNetLul := range EdgeIo2 {
		_, ipNet, _ := net.ParseCIDR(ipNetLul)
		edgeIo = append(edgeIo, ipNet)
	}

	for _, CDNIp := range bunnyCDNIPs {
		bunnyCDN = append(bunnyCDN, net.ParseIP(CDNIp))
	}

	_, range16, _ := net.ParseCIDR("23.235.32.0/20")
	_, range17, _ := net.ParseCIDR("43.249.72.0/22")
	_, range18, _ := net.ParseCIDR("103.244.50.0/24")
	_, range19, _ := net.ParseCIDR("103.245.222.0/23")
	_, range20, _ := net.ParseCIDR("103.245.224.0/24")
	_, range21, _ := net.ParseCIDR("104.156.80.0/20")
	_, range22, _ := net.ParseCIDR("151.101.0.0/16")
	_, range23, _ := net.ParseCIDR("157.52.64.0/18")
	_, range24, _ := net.ParseCIDR("172.111.64.0/18")
	_, range25, _ := net.ParseCIDR("185.31.16.0/22")
	_, range26, _ := net.ParseCIDR("199.27.72.0/21")
	_, range27, _ := net.ParseCIDR("199.232.0.0/16")
	_, range43, _ := net.ParseCIDR("146.75.116.0/22")

	fastly = append(fastly, range16)
	fastly = append(fastly, range17)
	fastly = append(fastly, range18)
	fastly = append(fastly, range19)
	fastly = append(fastly, range20)
	fastly = append(fastly, range21)
	fastly = append(fastly, range22)
	fastly = append(fastly, range23)
	fastly = append(fastly, range24)
	fastly = append(fastly, range25)
	fastly = append(fastly, range26)
	fastly = append(fastly, range27)
	fastly = append(fastly, range43)

	_, range28, _ := net.ParseCIDR("173.245.48.0/20")
	_, range29, _ := net.ParseCIDR("103.21.244.0/22")
	_, range30, _ := net.ParseCIDR("103.22.200.0/22")
	_, range31, _ := net.ParseCIDR("103.31.4.0/22")
	_, range32, _ := net.ParseCIDR("141.101.64.0/18")
	_, range33, _ := net.ParseCIDR("108.162.192.0/18")
	_, range34, _ := net.ParseCIDR("190.93.240.0/20")
	_, range35, _ := net.ParseCIDR("188.114.96.0/20")
	_, range36, _ := net.ParseCIDR("197.234.240.0/22")
	_, range37, _ := net.ParseCIDR("198.41.128.0/17")
	_, range38, _ := net.ParseCIDR("162.158.0.0/15")
	_, range39, _ := net.ParseCIDR("104.16.0.0/13")
	_, range40, _ := net.ParseCIDR("104.24.0.0/14")
	_, range41, _ := net.ParseCIDR("172.64.0.0/13")
	_, range42, _ := net.ParseCIDR("131.0.72.0/22")
	_, range44, _ := net.ParseCIDR("23.227.38.0/23")

	cloudflare = append(cloudflare, range28)
	cloudflare = append(cloudflare, range29)
	cloudflare = append(cloudflare, range30)
	cloudflare = append(cloudflare, range31)
	cloudflare = append(cloudflare, range32)
	cloudflare = append(cloudflare, range33)
	cloudflare = append(cloudflare, range34)
	cloudflare = append(cloudflare, range35)
	cloudflare = append(cloudflare, range36)
	cloudflare = append(cloudflare, range37)
	cloudflare = append(cloudflare, range38)
	cloudflare = append(cloudflare, range39)
	cloudflare = append(cloudflare, range40)
	cloudflare = append(cloudflare, range41)
	cloudflare = append(cloudflare, range42)
	cloudflare = append(cloudflare, range44)

	fmt.Println("Finished loading IP ranges")
}

func loadCloudFrontIPs() CloudfrontIPS {
	//open jsonFile
	jsonFile, err := os.Open("cloudfront.json")
	if err != nil {
		fmt.Println(err)
	}
	defer func(jsonFile *os.File) {
		err := jsonFile.Close()
		if err != nil {
			panic(err)
		}
	}(jsonFile)

	// read jsonFile as a byte array
	byteValue, _ := io.ReadAll(jsonFile)

	// initialize CloudfrontIPS struct
	var cloudfrontIPS CloudfrontIPS

	// unmarshal byteValue into cloudfrontIPS
	err = json.Unmarshal(byteValue, &cloudfrontIPS)
	if err != nil {
		fmt.Println(err)
	}

	return cloudfrontIPS
}
