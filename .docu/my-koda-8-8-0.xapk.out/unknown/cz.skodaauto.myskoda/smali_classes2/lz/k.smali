.class public final Llz/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljz/s;

.field public final b:Llz/e;

.field public final c:Lkf0/b0;


# direct methods
.method public constructor <init>(Ljz/s;Llz/e;Lkf0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/k;->a:Ljz/s;

    .line 5
    .line 6
    iput-object p2, p0, Llz/k;->b:Llz/e;

    .line 7
    .line 8
    iput-object p3, p0, Llz/k;->c:Lkf0/b0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Llz/k;->c:Lkf0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Le71/e;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x6

    .line 20
    iget-object v4, p0, Llz/k;->a:Ljz/s;

    .line 21
    .line 22
    invoke-direct {v0, v3, v4, p0, v2}, Le71/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method
