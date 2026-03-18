.class public final Lgw0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# instance fields
.field public final d:Lvw0/a;

.field public final e:Ljava/lang/Object;

.field public final f:Lay0/k;

.field public g:Lay0/a;


# direct methods
.method public constructor <init>(Lvw0/a;Ljava/lang/Object;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "config"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lgw0/d;->d:Lvw0/a;

    .line 15
    .line 16
    iput-object p2, p0, Lgw0/d;->e:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object p3, p0, Lgw0/d;->f:Lay0/k;

    .line 19
    .line 20
    new-instance p1, Lz81/g;

    .line 21
    .line 22
    const/4 p2, 0x2

    .line 23
    invoke-direct {p1, p2}, Lz81/g;-><init>(I)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lgw0/d;->g:Lay0/a;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/d;->g:Lay0/a;

    .line 2
    .line 3
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method
