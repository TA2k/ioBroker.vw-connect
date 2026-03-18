.class public abstract Lq41/b;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>(Lq41/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 9
    .line 10
    new-instance v0, Lyy0/l1;

    .line 11
    .line 12
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lq41/b;->e:Lyy0/l1;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a()Lq41/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lq41/b;->d:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lq41/a;

    .line 8
    .line 9
    return-object p0
.end method
