.class public final Lyz/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lfj0/a;


# direct methods
.method public constructor <init>(Lfj0/b;Lfj0/c;Ltr0/b;Lfj0/a;)V
    .locals 9

    .line 1
    new-instance v0, Lyz/a;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    invoke-direct {v0, v2, v2, v1, v1}, Lyz/a;-><init>(Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p3, p0, Lyz/c;->h:Ltr0/b;

    .line 14
    .line 15
    iput-object p4, p0, Lyz/c;->i:Lfj0/a;

    .line 16
    .line 17
    new-instance v3, Lvh/j;

    .line 18
    .line 19
    const/4 v8, 0x0

    .line 20
    const/16 v4, 0x9

    .line 21
    .line 22
    move-object v7, p0

    .line 23
    move-object v6, p1

    .line 24
    move-object v5, p2

    .line 25
    invoke-direct/range {v3 .. v8}, Lvh/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v7, v3}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
