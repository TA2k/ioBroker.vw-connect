.class public final Lvy0/p;
.super Lvy0/l1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/o;


# instance fields
.field public final h:Lvy0/p1;


# direct methods
.method public constructor <init>(Lvy0/p1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Laz0/i;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvy0/p;->h:Lvy0/p1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Throwable;)Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvy0/l1;->i()Lvy0/p1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1}, Lvy0/p1;->F(Ljava/lang/Throwable;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final j()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final k(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lvy0/p;->h:Lvy0/p1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvy0/l1;->i()Lvy0/p1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p1, p0}, Lvy0/p1;->z(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method
