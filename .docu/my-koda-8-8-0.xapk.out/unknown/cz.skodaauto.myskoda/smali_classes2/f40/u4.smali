.class public final Lf40/u4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwr0/h;

.field public final b:Ld40/n;


# direct methods
.method public constructor <init>(Ld40/n;Lwr0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lf40/u4;->a:Lwr0/h;

    .line 5
    .line 6
    iput-object p1, p0, Lf40/u4;->b:Ld40/n;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lf40/t4;)Lyy0/m1;
    .locals 3

    .line 1
    new-instance v0, Le1/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x12

    .line 5
    .line 6
    invoke-direct {v0, v2, p0, p1, v1}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lf40/t4;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lf40/u4;->a(Lf40/t4;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
