.class public final Lcb0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrs0/b;

.field public final b:Lkc0/i;

.field public final c:Lwr0/e;

.field public final d:Lfj0/b;

.field public final e:Lbq0/j;

.field public final f:Lbd0/c;

.field public final g:Lam0/c;

.field public final h:Lcb0/a;


# direct methods
.method public constructor <init>(Lrs0/b;Lkc0/i;Lwr0/e;Lfj0/b;Lbq0/j;Lbd0/c;Lam0/c;Lcb0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcb0/d;->a:Lrs0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lcb0/d;->b:Lkc0/i;

    .line 7
    .line 8
    iput-object p3, p0, Lcb0/d;->c:Lwr0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lcb0/d;->d:Lfj0/b;

    .line 11
    .line 12
    iput-object p5, p0, Lcb0/d;->e:Lbq0/j;

    .line 13
    .line 14
    iput-object p6, p0, Lcb0/d;->f:Lbd0/c;

    .line 15
    .line 16
    iput-object p7, p0, Lcb0/d;->g:Lam0/c;

    .line 17
    .line 18
    iput-object p8, p0, Lcb0/d;->h:Lcb0/a;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Ldb0/a;

    .line 2
    .line 3
    new-instance p2, Lcb0/c;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p2, p0, p1, v0}, Lcb0/c;-><init>(Lcb0/d;Ldb0/a;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, p2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
