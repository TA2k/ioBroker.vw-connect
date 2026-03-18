.class public final Lgi0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lgi0/b;


# direct methods
.method public constructor <init>(Lgi0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgi0/a;->a:Lgi0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lgi0/a;->a:Lgi0/b;

    .line 2
    .line 3
    check-cast p0, Lei0/a;

    .line 4
    .line 5
    iget-object p0, p0, Lei0/a;->b:Lyy0/k1;

    .line 6
    .line 7
    new-instance v0, Lal0/f;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, p0, v1}, Lal0/f;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lyy0/m1;

    .line 14
    .line 15
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
