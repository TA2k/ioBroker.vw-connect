.class public final Lw70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbq0/n;

.field public final b:Lw70/m;

.field public final c:Lgb0/a0;

.field public final d:Lu70/c;

.field public final e:Lsf0/a;


# direct methods
.method public constructor <init>(Lbq0/n;Lw70/m;Lgb0/a0;Lu70/c;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/c;->a:Lbq0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/c;->b:Lw70/m;

    .line 7
    .line 8
    iput-object p3, p0, Lw70/c;->c:Lgb0/a0;

    .line 9
    .line 10
    iput-object p4, p0, Lw70/c;->d:Lu70/c;

    .line 11
    .line 12
    iput-object p5, p0, Lw70/c;->e:Lsf0/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lx70/f;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lw70/c;->b(Lx70/f;)Lam0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lx70/f;)Lam0/i;
    .locals 3

    .line 1
    new-instance v0, Laa/i0;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, p0, p1, v2}, Laa/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p1, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lw70/c;->e:Lsf0/a;

    .line 15
    .line 16
    invoke-static {p1, p0, v2}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
