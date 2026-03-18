.class public final Lm70/d0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/l;

.field public final i:Lij0/a;


# direct methods
.method public constructor <init>(Lcs0/l;Lij0/a;)V
    .locals 11

    .line 1
    new-instance v0, Lm70/b0;

    .line 2
    .line 3
    new-instance v1, Lm70/a0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x7

    .line 7
    invoke-direct {v1, v2, v2, v3}, Lm70/a0;-><init>(Ljava/util/ArrayList;Ljava/util/List;I)V

    .line 8
    .line 9
    .line 10
    new-instance v4, Lvf0/a;

    .line 11
    .line 12
    const/4 v8, 0x0

    .line 13
    const/4 v10, 0x0

    .line 14
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 15
    .line 16
    const/4 v7, 0x0

    .line 17
    move-object v6, v5

    .line 18
    move-object v9, v5

    .line 19
    invoke-direct/range {v4 .. v10}, Lvf0/a;-><init>(Ljava/util/List;Ljava/util/List;ILjava/lang/Number;Ljava/util/List;F)V

    .line 20
    .line 21
    .line 22
    const-string v2, ""

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    invoke-direct {v0, v1, v4, v2, v3}, Lm70/b0;-><init>(Lm70/a0;Lvf0/a;Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lm70/d0;->h:Lcs0/l;

    .line 32
    .line 33
    iput-object p2, p0, Lm70/d0;->i:Lij0/a;

    .line 34
    .line 35
    return-void
.end method
