.class public final Lp60/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lln0/l;


# direct methods
.method public constructor <init>(Lln0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/i0;->a:Lln0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp60/i0;->a:Lln0/l;

    .line 8
    .line 9
    iget-object v0, p0, Lln0/l;->a:Lxl0/f;

    .line 10
    .line 11
    new-instance v1, Lln0/k;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v1, p0, p1, p2, v2}, Lln0/k;-><init>(Lln0/l;JLkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
