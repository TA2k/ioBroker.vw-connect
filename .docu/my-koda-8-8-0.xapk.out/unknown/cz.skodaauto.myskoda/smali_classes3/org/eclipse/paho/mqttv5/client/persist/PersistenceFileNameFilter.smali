.class public Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileNameFilter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/FilenameFilter;


# instance fields
.field private final fileExtension:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileNameFilter;->fileExtension:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public accept(Ljava/io/File;Ljava/lang/String;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileNameFilter;->fileExtension:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p2, p0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
