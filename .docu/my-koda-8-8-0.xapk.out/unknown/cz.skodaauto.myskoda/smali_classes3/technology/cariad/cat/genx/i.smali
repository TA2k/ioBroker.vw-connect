.class public final synthetic Ltechnology/cariad/cat/genx/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/GenXDispatcherImpl;

.field public final synthetic e:J

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/i;->d:Ltechnology/cariad/cat/genx/GenXDispatcherImpl;

    .line 5
    .line 6
    iput-wide p2, p0, Ltechnology/cariad/cat/genx/i;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Ltechnology/cariad/cat/genx/i;->f:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/i;->e:J

    .line 2
    .line 3
    iget-wide v2, p0, Ltechnology/cariad/cat/genx/i;->f:J

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/i;->d:Ltechnology/cariad/cat/genx/GenXDispatcherImpl;

    .line 6
    .line 7
    invoke-static {p0, v0, v1, v2, v3}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->f(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)Llx0/b0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
