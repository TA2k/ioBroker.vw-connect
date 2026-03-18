.class public final Lbo0/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lyn0/c;

.field public final i:Lyn0/l;

.field public final j:Ltr0/b;

.field public k:Lao0/a;


# direct methods
.method public constructor <init>(Lyn0/c;Lyn0/l;Ltr0/b;)V
    .locals 4

    .line 1
    new-instance v0, Lbo0/c;

    .line 2
    .line 3
    invoke-static {}, Ljava/time/LocalTime;->now()Ljava/time/LocalTime;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "now(...)"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {}, Ljava/time/LocalTime;->now()Ljava/time/LocalTime;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-direct {v0, v1, v3, v2, v2}, Lbo0/c;-><init>(Ljava/time/LocalTime;Ljava/time/LocalTime;ZZ)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lbo0/d;->h:Lyn0/c;

    .line 27
    .line 28
    iput-object p2, p0, Lbo0/d;->i:Lyn0/l;

    .line 29
    .line 30
    iput-object p3, p0, Lbo0/d;->j:Ltr0/b;

    .line 31
    .line 32
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    new-instance p2, La50/a;

    .line 37
    .line 38
    const/16 p3, 0xa

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    invoke-direct {p2, p0, v0, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x3

    .line 45
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    return-void
.end method
