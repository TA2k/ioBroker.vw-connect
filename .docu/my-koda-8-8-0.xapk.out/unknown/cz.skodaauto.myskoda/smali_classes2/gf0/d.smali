.class public final Lgf0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lgf0/h;


# direct methods
.method public constructor <init>(Lgf0/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgf0/d;->a:Lgf0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lgf0/d;->a:Lgf0/h;

    .line 2
    .line 3
    check-cast p0, Ldf0/b;

    .line 4
    .line 5
    iget-object p0, p0, Ldf0/b;->a:Ljava/lang/String;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-static {p0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->box-impl(Ljava/lang/String;)Lcz/skodaauto/myskoda/library/deeplink/model/Link;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return-object p0
.end method
