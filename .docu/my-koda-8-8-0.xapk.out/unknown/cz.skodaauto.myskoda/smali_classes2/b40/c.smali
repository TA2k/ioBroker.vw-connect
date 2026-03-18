.class public final Lb40/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Lzd0/a;

.field public final k:Lz30/e;


# direct methods
.method public constructor <init>(Lfo0/b;Lfo0/c;Lzd0/a;Lz30/e;)V
    .locals 1

    .line 1
    sget-object v0, Lb40/b;->a:Lb40/b;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lb40/c;->h:Lfo0/b;

    .line 7
    .line 8
    iput-object p2, p0, Lb40/c;->i:Lfo0/c;

    .line 9
    .line 10
    iput-object p3, p0, Lb40/c;->j:Lzd0/a;

    .line 11
    .line 12
    iput-object p4, p0, Lb40/c;->k:Lz30/e;

    .line 13
    .line 14
    new-instance p1, La50/a;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    const/4 p3, 0x6

    .line 18
    invoke-direct {p1, p0, p2, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
