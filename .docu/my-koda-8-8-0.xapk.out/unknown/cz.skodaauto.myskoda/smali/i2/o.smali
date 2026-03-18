.class public final Li2/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/i1;


# instance fields
.field public final a:Lg1/a0;

.field public final synthetic b:Li2/p;


# direct methods
.method public constructor <init>(Li2/p;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li2/o;->b:Li2/p;

    .line 5
    .line 6
    new-instance v0, Lg1/a0;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    invoke-direct {v0, p1, v1}, Lg1/a0;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Li2/o;->a:Lg1/a0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Le1/e;Lg1/c1;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Le1/w0;->e:Le1/w0;

    .line 2
    .line 3
    new-instance v1, La7/l0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, p1, v2}, La7/l0;-><init>(Li2/o;Le1/e;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Li2/o;->b:Li2/p;

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1, p2}, Li2/p;->a(Le1/w0;La7/l0;Lrx0/c;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
