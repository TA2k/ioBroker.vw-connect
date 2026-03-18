.class public final Lal0/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/e0;


# direct methods
.method public constructor <init>(Lal0/e0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/x0;->a:Lal0/e0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lal0/x0;->a:Lal0/e0;

    .line 2
    .line 3
    check-cast p0, Lyk0/j;

    .line 4
    .line 5
    iget-object p0, p0, Lyk0/j;->h:Lyy0/c2;

    .line 6
    .line 7
    new-instance v0, La00/a;

    .line 8
    .line 9
    const/16 v1, 0x13

    .line 10
    .line 11
    invoke-direct {v0, v1}, La00/a;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Le71/e;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-direct {v1, v0, p0, v2}, Le71/e;-><init>(Lay0/k;Lyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    new-instance p0, Lyy0/m1;

    .line 21
    .line 22
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 23
    .line 24
    .line 25
    return-object p0
.end method
