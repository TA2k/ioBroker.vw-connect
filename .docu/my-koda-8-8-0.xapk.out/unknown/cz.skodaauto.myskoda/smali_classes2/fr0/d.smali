.class public final Lfr0/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lkf0/k;


# direct methods
.method public constructor <init>(Lij0/a;Lkf0/k;)V
    .locals 6

    .line 1
    new-instance v0, Lfr0/c;

    .line 2
    .line 3
    const-string v2, ""

    .line 4
    .line 5
    sget-object v1, Ler0/g;->d:Ler0/g;

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    move-object v3, v2

    .line 10
    invoke-direct/range {v0 .. v5}, Lfr0/c;-><init>(Ler0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lkp/f8;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lfr0/d;->h:Lij0/a;

    .line 17
    .line 18
    iput-object p2, p0, Lfr0/d;->i:Lkf0/k;

    .line 19
    .line 20
    new-instance p1, Ldm0/h;

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    const/16 v0, 0x12

    .line 24
    .line 25
    invoke-direct {p1, p0, p2, v0}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
