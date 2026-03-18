.class public final Lw70/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lam0/c;

.field public final b:Lbq0/o;

.field public final c:Lw70/m;

.field public final d:Lgb0/a0;

.field public final e:Lwr0/i;


# direct methods
.method public constructor <init>(Lam0/c;Lbq0/o;Lw70/m;Lgb0/a0;Lwr0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/j;->a:Lam0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/j;->b:Lbq0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lw70/j;->c:Lw70/m;

    .line 9
    .line 10
    iput-object p4, p0, Lw70/j;->d:Lgb0/a0;

    .line 11
    .line 12
    iput-object p5, p0, Lw70/j;->e:Lwr0/i;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    new-instance p1, Lw70/i;

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    invoke-direct {p1, p0, p2}, Lw70/i;-><init>(Lw70/j;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
