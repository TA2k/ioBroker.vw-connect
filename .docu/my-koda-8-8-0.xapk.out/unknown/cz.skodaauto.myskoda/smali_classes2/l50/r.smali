.class public final Ll50/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lj50/k;

.field public final b:Ll50/k;


# direct methods
.method public constructor <init>(Lj50/k;Ll50/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/r;->a:Lj50/k;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/r;->b:Ll50/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Ll50/r;->b:Ll50/k;

    .line 4
    .line 5
    check-cast p1, Liy/b;

    .line 6
    .line 7
    sget-object v0, Lly/b;->a2:Lly/b;

    .line 8
    .line 9
    invoke-interface {p1, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Ll50/r;->a:Lj50/k;

    .line 13
    .line 14
    iget-object p0, p0, Lj50/k;->c:Lyy0/k1;

    .line 15
    .line 16
    invoke-static {p0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
