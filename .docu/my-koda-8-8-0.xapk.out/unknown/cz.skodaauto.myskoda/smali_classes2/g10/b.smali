.class public final Lg10/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Le10/e;

.field public final i:Le10/d;

.field public final j:Lgn0/f;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Le10/e;Le10/d;Lgn0/f;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lg10/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v3, v1, v2}, Lg10/a;-><init>(Lql0/g;ZLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lg10/b;->h:Le10/e;

    .line 14
    .line 15
    iput-object p2, p0, Lg10/b;->i:Le10/d;

    .line 16
    .line 17
    iput-object p3, p0, Lg10/b;->j:Lgn0/f;

    .line 18
    .line 19
    iput-object p4, p0, Lg10/b;->k:Lij0/a;

    .line 20
    .line 21
    new-instance p1, Ldm0/h;

    .line 22
    .line 23
    const/16 p2, 0x15

    .line 24
    .line 25
    invoke-direct {p1, p0, v3, p2}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
