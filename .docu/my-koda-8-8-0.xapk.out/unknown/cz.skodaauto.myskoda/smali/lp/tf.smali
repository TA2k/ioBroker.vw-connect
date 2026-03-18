.class public abstract Llp/tf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final d(Llf0/i;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Llf0/i;->f:Llf0/i;

    .line 7
    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    sget-object v0, Llf0/i;->g:Llf0/i;

    .line 11
    .line 12
    if-ne p0, v0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 18
    return p0
.end method


# virtual methods
.method public abstract a(Ly4/g;Ly4/c;Ly4/c;)Z
.end method

.method public abstract b(Ly4/g;Ljava/lang/Object;Ljava/lang/Object;)Z
.end method

.method public abstract c(Ly4/g;Ly4/f;Ly4/f;)Z
.end method

.method public abstract e(Ly4/f;Ly4/f;)V
.end method

.method public abstract f(Ly4/f;Ljava/lang/Thread;)V
.end method
