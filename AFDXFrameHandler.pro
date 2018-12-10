QT += core
QT -= gui

CONFIG += c++11

TARGET = AFDXFrameHandler
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    AFDXFramePrase.cpp

HEADERS += \
    AFDXFramePrase.h
