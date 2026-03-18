.class public final Lu61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo71/a;


# direct methods
.method public static f(Ljava/lang/String;Ljava/lang/String;Lt51/i;)V
    .locals 9

    .line 1
    const-string v0, "getName(...)"

    .line 2
    .line 3
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v7

    .line 7
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 8
    .line 9
    .line 10
    move-result-object v8

    .line 11
    const-string v0, "now(...)"

    .line 12
    .line 13
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lt51/j;

    .line 17
    .line 18
    new-instance v4, Lac0/a;

    .line 19
    .line 20
    const/16 v0, 0x1d

    .line 21
    .line 22
    invoke-direct {v4, p0, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    const-string v2, "RemoteParkAssistPlugin"

    .line 27
    .line 28
    move-object v6, p1

    .line 29
    move-object v3, p2

    .line 30
    invoke-direct/range {v1 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;Ljava/time/Instant;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
