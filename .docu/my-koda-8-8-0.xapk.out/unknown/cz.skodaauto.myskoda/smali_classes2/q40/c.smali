.class public final Lq40/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lxh0/d;

.field public final i:Lnn0/j;

.field public final j:Lo40/t;

.field public final k:Ljava/lang/Class;

.field public final l:Lo40/s;

.field public final m:Lo40/f;

.field public final n:Ltr0/b;


# direct methods
.method public constructor <init>(Lo40/h;Lxh0/d;Lnn0/j;Lo40/t;Ljava/lang/Class;Lo40/s;Lo40/f;Ltr0/b;)V
    .locals 4

    .line 1
    new-instance v0, Lq40/a;

    .line 2
    .line 3
    const-string v1, "00:02:00"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v1, v3, v3}, Lq40/a;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lq40/c;->h:Lxh0/d;

    .line 14
    .line 15
    iput-object p3, p0, Lq40/c;->i:Lnn0/j;

    .line 16
    .line 17
    iput-object p4, p0, Lq40/c;->j:Lo40/t;

    .line 18
    .line 19
    iput-object p5, p0, Lq40/c;->k:Ljava/lang/Class;

    .line 20
    .line 21
    iput-object p6, p0, Lq40/c;->l:Lo40/s;

    .line 22
    .line 23
    iput-object p7, p0, Lq40/c;->m:Lo40/f;

    .line 24
    .line 25
    iput-object p8, p0, Lq40/c;->n:Ltr0/b;

    .line 26
    .line 27
    new-instance p2, Lnz/g;

    .line 28
    .line 29
    const/16 p3, 0xa

    .line 30
    .line 31
    invoke-direct {p2, p3, p0, p1, v3}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
