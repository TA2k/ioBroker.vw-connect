.class public final Ldo0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/k1;

.field public final d:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/4 v1, 0x5

    .line 6
    const/16 v2, 0xa

    .line 7
    .line 8
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Ldo0/a;->a:Lyy0/q1;

    .line 13
    .line 14
    sget-object v1, Lgo0/c;->e:Lgo0/c;

    .line 15
    .line 16
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iput-object v1, p0, Ldo0/a;->b:Lyy0/c2;

    .line 21
    .line 22
    new-instance v2, Lyy0/k1;

    .line 23
    .line 24
    invoke-direct {v2, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 25
    .line 26
    .line 27
    iput-object v2, p0, Ldo0/a;->c:Lyy0/k1;

    .line 28
    .line 29
    new-instance v0, Lyy0/l1;

    .line 30
    .line 31
    invoke-direct {v0, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Ldo0/a;->d:Lyy0/l1;

    .line 35
    .line 36
    return-void
.end method
