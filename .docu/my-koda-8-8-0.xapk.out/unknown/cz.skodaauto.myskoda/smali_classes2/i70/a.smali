.class public final Li70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# instance fields
.field public final d:Lez0/c;

.field public final e:Ljava/lang/Object;

.field public final f:Lyy0/c2;


# direct methods
.method public constructor <init>()V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Li70/a;->d:Lez0/c;

    .line 9
    .line 10
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 11
    .line 12
    new-instance v1, Lbp0/h;

    .line 13
    .line 14
    const/4 v2, 0x7

    .line 15
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Li70/a;->e:Ljava/lang/Object;

    .line 23
    .line 24
    new-instance v1, Lne0/c;

    .line 25
    .line 26
    new-instance v2, Ljava/lang/Exception;

    .line 27
    .line 28
    const-string v0, "Missing data"

    .line 29
    .line 30
    invoke-direct {v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    const/16 v6, 0x1e

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    iput-object v0, p0, Li70/a;->f:Lyy0/c2;

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
