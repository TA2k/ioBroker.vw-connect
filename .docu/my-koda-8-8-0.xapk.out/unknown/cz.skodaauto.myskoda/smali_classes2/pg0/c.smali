.class public final Lpg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpg0/a;


# direct methods
.method public constructor <init>(Lpg0/f;Lpg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lpg0/c;->a:Lpg0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lpg0/c;->a:Lpg0/a;

    .line 2
    .line 3
    check-cast v0, Lng0/a;

    .line 4
    .line 5
    iget-object v0, v0, Lng0/a;->a:Lve0/u;

    .line 6
    .line 7
    const-string v1, "end_of_support_notified_version"

    .line 8
    .line 9
    const-wide/16 v2, -0x1

    .line 10
    .line 11
    invoke-virtual {v0, v2, v3, v1}, Lve0/u;->i(JLjava/lang/String;)Lub0/e;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    new-instance v1, Llb0/y;

    .line 16
    .line 17
    const/4 v2, 0x5

    .line 18
    invoke-direct {v1, v2, v0, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-object v1
.end method
