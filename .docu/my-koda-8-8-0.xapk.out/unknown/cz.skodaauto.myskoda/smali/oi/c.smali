.class public final Loi/c;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Loi/b;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;


# direct methods
.method public constructor <init>(Lyy0/l1;)V
    .locals 5

    .line 1
    sget-object v0, Loi/b;->d:Loi/b;

    .line 2
    .line 3
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Loi/c;->d:Loi/b;

    .line 7
    .line 8
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Loi/c;->e:Lyy0/c2;

    .line 15
    .line 16
    new-instance v1, Lgc/a;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-direct {v1, p0, v3, v2}, Lgc/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lbn0/f;

    .line 24
    .line 25
    const/4 v4, 0x5

    .line 26
    invoke-direct {v2, v0, p1, v1, v4}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    sget-object v0, Lyy0/u1;->a:Lyy0/w1;

    .line 34
    .line 35
    invoke-static {v2, p1, v0, v3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Loi/c;->f:Lyy0/l1;

    .line 40
    .line 41
    return-void
.end method
