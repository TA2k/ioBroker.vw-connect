.class public final Lgw0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lzv0/c;

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/util/ArrayList;

.field public final d:Lz81/g;


# direct methods
.method public constructor <init>(Lvw0/a;Lzv0/c;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "client"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p1, "pluginConfig"

    .line 12
    .line 13
    invoke-static {p3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p2, p0, Lgw0/b;->a:Lzv0/c;

    .line 20
    .line 21
    iput-object p3, p0, Lgw0/b;->b:Ljava/lang/Object;

    .line 22
    .line 23
    new-instance p1, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lgw0/b;->c:Ljava/util/ArrayList;

    .line 29
    .line 30
    new-instance p1, Lz81/g;

    .line 31
    .line 32
    const/4 p2, 0x2

    .line 33
    invoke-direct {p1, p2}, Lz81/g;-><init>(I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lgw0/b;->d:Lz81/g;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a(Lgw0/a;Lrx0/i;)V
    .locals 1

    .line 1
    const-string v0, "hook"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lgw0/e;

    .line 7
    .line 8
    invoke-direct {v0, p1, p2}, Lgw0/e;-><init>(Lgw0/a;Lrx0/i;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lgw0/b;->c:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method
