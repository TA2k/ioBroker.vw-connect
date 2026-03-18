.class public final Lw30/j0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lu30/f;

.field public final i:Lu30/j0;

.field public final j:Lwr0/i;

.field public final k:Lij0/a;

.field public final l:Lrq0/d;


# direct methods
.method public constructor <init>(Lu30/f;Lu30/j0;Lwr0/i;Lij0/a;Lrq0/d;)V
    .locals 9

    .line 1
    new-instance v0, Lw30/i0;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const/4 v4, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const-string v5, ""

    .line 8
    .line 9
    move-object v6, v5

    .line 10
    move-object v7, v5

    .line 11
    move-object v8, v5

    .line 12
    invoke-direct/range {v0 .. v8}, Lw30/i0;-><init>(Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lw30/j0;->h:Lu30/f;

    .line 19
    .line 20
    iput-object p2, p0, Lw30/j0;->i:Lu30/j0;

    .line 21
    .line 22
    iput-object p3, p0, Lw30/j0;->j:Lwr0/i;

    .line 23
    .line 24
    iput-object p4, p0, Lw30/j0;->k:Lij0/a;

    .line 25
    .line 26
    iput-object p5, p0, Lw30/j0;->l:Lrq0/d;

    .line 27
    .line 28
    new-instance p1, Lw30/h0;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    const/4 p3, 0x0

    .line 32
    invoke-direct {p1, p0, p3, p2}, Lw30/h0;-><init>(Lw30/j0;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    new-instance p1, Lw30/h0;

    .line 39
    .line 40
    const/4 p2, 0x1

    .line 41
    invoke-direct {p1, p0, p3, p2}, Lw30/h0;-><init>(Lw30/j0;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method
