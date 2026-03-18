.class public interface abstract Ll9/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public b([BII)Ll9/d;
    .locals 6

    .line 1
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    new-instance v5, Lgr/k;

    .line 6
    .line 7
    const/16 v0, 0xc

    .line 8
    .line 9
    invoke-direct {v5, p2, v0}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    sget-object v4, Ll9/i;->c:Ll9/i;

    .line 14
    .line 15
    move-object v0, p0

    .line 16
    move-object v1, p1

    .line 17
    move v3, p3

    .line 18
    invoke-interface/range {v0 .. v5}, Ll9/j;->g([BIILl9/i;Lw7/f;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Ll9/b;

    .line 22
    .line 23
    invoke-virtual {p2}, Lhr/e0;->i()Lhr/x0;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-direct {p0, p1}, Ll9/b;-><init>(Lhr/x0;)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public abstract g([BIILl9/i;Lw7/f;)V
.end method

.method public reset()V
    .locals 0

    .line 1
    return-void
.end method
