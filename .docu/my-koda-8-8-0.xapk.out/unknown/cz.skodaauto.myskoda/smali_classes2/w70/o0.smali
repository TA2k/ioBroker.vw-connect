.class public final Lw70/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lu70/c;

.field public final b:Lbq0/h;

.field public final c:Lkf0/o;


# direct methods
.method public constructor <init>(Lu70/c;Lbq0/h;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/o0;->a:Lu70/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/o0;->b:Lbq0/h;

    .line 7
    .line 8
    iput-object p3, p0, Lw70/o0;->c:Lkf0/o;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lcq0/i;

    .line 2
    .line 3
    iget-object p2, p0, Lw70/o0;->c:Lkf0/o;

    .line 4
    .line 5
    invoke-static {p2}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    new-instance v0, Lo20/c;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/16 v2, 0x14

    .line 13
    .line 14
    invoke-direct {v0, v2, p0, p1, v1}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p2, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
