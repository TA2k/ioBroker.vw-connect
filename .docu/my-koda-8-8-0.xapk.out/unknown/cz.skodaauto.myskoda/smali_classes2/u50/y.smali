.class public final Lu50/y;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ls50/i;

.field public final i:Ls50/z;

.field public final j:Ltr0/b;


# direct methods
.method public constructor <init>(Ls50/i;Ls50/z;Ltr0/b;)V
    .locals 1

    .line 1
    new-instance v0, Lu50/x;

    .line 2
    .line 3
    invoke-direct {v0}, Lu50/x;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu50/y;->h:Ls50/i;

    .line 10
    .line 11
    iput-object p2, p0, Lu50/y;->i:Ls50/z;

    .line 12
    .line 13
    iput-object p3, p0, Lu50/y;->j:Ltr0/b;

    .line 14
    .line 15
    new-instance p1, Lm70/f1;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    const/16 p3, 0x18

    .line 19
    .line 20
    invoke-direct {p1, p0, p2, p3}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
