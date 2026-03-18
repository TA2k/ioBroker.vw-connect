.class public final Lbm/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbm/j;


# instance fields
.field public final a:Lez0/i;

.field public final b:Lbm/n;


# direct methods
.method public constructor <init>(Lez0/i;Lbm/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbm/c;->a:Lez0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lbm/c;->b:Lbm/n;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ldm/i;Lmm/n;)Lbm/k;
    .locals 2

    .line 1
    new-instance v0, Lbm/e;

    .line 2
    .line 3
    iget-object p1, p1, Ldm/i;->a:Lbm/q;

    .line 4
    .line 5
    iget-object v1, p0, Lbm/c;->a:Lez0/i;

    .line 6
    .line 7
    iget-object p0, p0, Lbm/c;->b:Lbm/n;

    .line 8
    .line 9
    invoke-direct {v0, p1, p2, v1, p0}, Lbm/e;-><init>(Lbm/q;Lmm/n;Lez0/i;Lbm/n;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
