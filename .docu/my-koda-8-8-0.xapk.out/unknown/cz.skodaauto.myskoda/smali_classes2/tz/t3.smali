.class public final Ltz/t3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lrz/f0;

.field public final i:Lrz/i0;


# direct methods
.method public constructor <init>(Lgb0/f;Lrz/f0;Lrz/i0;)V
    .locals 2

    .line 1
    new-instance v0, Ltz/s3;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltz/s3;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, Ltz/t3;->h:Lrz/f0;

    .line 11
    .line 12
    iput-object p3, p0, Ltz/t3;->i:Lrz/i0;

    .line 13
    .line 14
    new-instance p2, Ltz/o2;

    .line 15
    .line 16
    const/4 p3, 0x0

    .line 17
    const/4 v0, 0x5

    .line 18
    invoke-direct {p2, v0, p1, p0, p3}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
