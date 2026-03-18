.class public final synthetic Ltechnology/cariad/cat/genx/wifi/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:[B

.field public final synthetic h:Ljava/net/InetAddress;

.field public final synthetic i:Ljava/net/InetAddress;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/b;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/b;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/b;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Ltechnology/cariad/cat/genx/wifi/b;->g:[B

    .line 11
    .line 12
    iput-object p5, p0, Ltechnology/cariad/cat/genx/wifi/b;->h:Ljava/net/InetAddress;

    .line 13
    .line 14
    iput-object p6, p0, Ltechnology/cariad/cat/genx/wifi/b;->i:Ljava/net/InetAddress;

    .line 15
    .line 16
    iput p7, p0, Ltechnology/cariad/cat/genx/wifi/b;->j:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v5, p0, Ltechnology/cariad/cat/genx/wifi/b;->i:Ljava/net/InetAddress;

    .line 2
    .line 3
    iget v6, p0, Ltechnology/cariad/cat/genx/wifi/b;->j:I

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/b;->d:Ljava/util/List;

    .line 6
    .line 7
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/b;->e:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/b;->f:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v3, p0, Ltechnology/cariad/cat/genx/wifi/b;->g:[B

    .line 12
    .line 13
    iget-object v4, p0, Ltechnology/cariad/cat/genx/wifi/b;->h:Ljava/net/InetAddress;

    .line 14
    .line 15
    invoke-static/range {v0 .. v6}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->B(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
