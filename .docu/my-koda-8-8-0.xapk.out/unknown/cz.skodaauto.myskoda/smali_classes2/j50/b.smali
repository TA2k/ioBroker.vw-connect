.class public final Lj50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll50/i;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/k1;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Llx0/l;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lj50/b;->a:Lyy0/c2;

    .line 19
    .line 20
    new-instance v1, Lyy0/l1;

    .line 21
    .line 22
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lj50/b;->b:Lyy0/l1;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    const/4 v1, 0x5

    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    iput-object v0, p0, Lj50/b;->c:Lyy0/q1;

    .line 35
    .line 36
    new-instance v1, Lyy0/k1;

    .line 37
    .line 38
    invoke-direct {v1, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 39
    .line 40
    .line 41
    iput-object v1, p0, Lj50/b;->d:Lyy0/k1;

    .line 42
    .line 43
    return-void
.end method
