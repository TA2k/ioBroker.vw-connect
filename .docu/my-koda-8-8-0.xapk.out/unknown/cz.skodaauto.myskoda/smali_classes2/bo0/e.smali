.class public final synthetic Lbo0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Z


# direct methods
.method public synthetic constructor <init>(JZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lbo0/e;->d:J

    .line 5
    .line 6
    iput-boolean p3, p0, Lbo0/e;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    new-instance v0, Llj0/e;

    .line 2
    .line 3
    const-string v1, "climate_plans_detail_plan_"

    .line 4
    .line 5
    const-string v2, "_switch"

    .line 6
    .line 7
    iget-wide v3, p0, Lbo0/e;->d:J

    .line 8
    .line 9
    invoke-static {v3, v4, v1, v2}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-boolean p0, p0, Lbo0/e;->e:Z

    .line 14
    .line 15
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
