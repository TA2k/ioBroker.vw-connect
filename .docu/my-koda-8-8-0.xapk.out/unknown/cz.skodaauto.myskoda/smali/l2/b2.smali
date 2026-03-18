.class public final Ll2/b2;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/z;


# instance fields
.field public final synthetic d:Lw2/b;

.field public final synthetic e:Ll2/c2;


# direct methods
.method public constructor <init>(Lw2/b;Ll2/c2;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ll2/b2;->d:Lw2/b;

    .line 2
    .line 3
    iput-object p2, p0, Ll2/b2;->e:Ll2/c2;

    .line 4
    .line 5
    sget-object p1, Lvy0/y;->d:Lvy0/y;

    .line 6
    .line 7
    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    new-instance v0, Lvu/d;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    iget-object v2, p0, Ll2/b2;->d:Lw2/b;

    .line 5
    .line 6
    iget-object p0, p0, Ll2/b2;->e:Ll2/c2;

    .line 7
    .line 8
    invoke-direct {v0, v1, v2, p0}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p2, v0}, Llp/tc;->c(Ljava/lang/Throwable;Lay0/a;)Z

    .line 12
    .line 13
    .line 14
    sget-object v0, Lvy0/y;->d:Lvy0/y;

    .line 15
    .line 16
    iget-object p0, p0, Ll2/c2;->d:Lpx0/g;

    .line 17
    .line 18
    invoke-interface {p0, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lvy0/z;

    .line 23
    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    invoke-interface {p0, p1, p2}, Lvy0/z;->handleException(Lpx0/g;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    throw p2
.end method
