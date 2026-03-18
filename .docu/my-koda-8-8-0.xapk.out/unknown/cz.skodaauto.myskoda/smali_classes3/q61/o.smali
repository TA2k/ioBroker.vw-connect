.class public final Lq61/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# static fields
.field public static final d:Lq61/o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lq61/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lq61/o;->d:Lq61/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v1, Lp81/c;

    .line 2
    .line 3
    const/16 p0, 0x19

    .line 4
    .line 5
    invoke-direct {v1, p0}, Lp81/c;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v2, Lp81/c;

    .line 9
    .line 10
    invoke-direct {v2, p0}, Lp81/c;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v3, Lg1/e1;

    .line 14
    .line 15
    const/4 p0, 0x3

    .line 16
    const/4 v0, 0x5

    .line 17
    const/4 v4, 0x0

    .line 18
    invoke-direct {v3, p0, v4, v0}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    new-instance v4, Lp81/c;

    .line 22
    .line 23
    const/16 p0, 0x19

    .line 24
    .line 25
    invoke-direct {v4, p0}, Lp81/c;-><init>(I)V

    .line 26
    .line 27
    .line 28
    move-object v0, p1

    .line 29
    move-object v5, p2

    .line 30
    invoke-static/range {v0 .. v5}, Lg1/g3;->d(Lp3/x;Lay0/k;Lay0/k;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    if-ne p0, p1, :cond_0

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0
.end method
