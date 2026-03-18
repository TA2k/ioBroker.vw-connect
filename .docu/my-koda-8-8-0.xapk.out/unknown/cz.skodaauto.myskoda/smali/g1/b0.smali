.class public final Lg1/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/i1;


# instance fields
.field public final a:La2/g;

.field public final b:Lg1/a0;

.field public final c:Le1/b1;


# direct methods
.method public constructor <init>(La2/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/b0;->a:La2/g;

    .line 5
    .line 6
    new-instance p1, Lg1/a0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p1, p0, v0}, Lg1/a0;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lg1/b0;->b:Lg1/a0;

    .line 13
    .line 14
    new-instance p1, Le1/b1;

    .line 15
    .line 16
    invoke-direct {p1}, Le1/b1;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lg1/b0;->c:Le1/b1;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Le1/e;Lg1/c1;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Le1/w0;->d:Le1/w0;

    .line 2
    .line 3
    new-instance v0, Le60/m;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, p0, p1, v1}, Le60/m;-><init>(Lg1/b0;Le1/e;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    if-ne p0, p1, :cond_0

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method
