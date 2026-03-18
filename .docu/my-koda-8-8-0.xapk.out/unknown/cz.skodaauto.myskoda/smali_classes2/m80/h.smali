.class public final Lm80/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/k;

.field public final i:Lk80/g;

.field public final j:Ltr0/b;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/k;Lk80/g;Ltr0/b;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lm80/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Ler0/g;->d:Ler0/g;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v2, v3}, Lm80/g;-><init>(ZZLer0/g;Lql0/g;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lm80/h;->h:Lkf0/k;

    .line 14
    .line 15
    iput-object p2, p0, Lm80/h;->i:Lk80/g;

    .line 16
    .line 17
    iput-object p3, p0, Lm80/h;->j:Ltr0/b;

    .line 18
    .line 19
    iput-object p4, p0, Lm80/h;->k:Lij0/a;

    .line 20
    .line 21
    new-instance p1, Lm80/f;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    invoke-direct {p1, p0, v3, p2}, Lm80/f;-><init>(Lm80/h;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
