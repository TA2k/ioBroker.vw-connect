.class public final Lgf0/g;
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
    iput-object p1, p0, Lgf0/g;->a:Lgf0/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcz/skodaauto/myskoda/library/deeplink/model/Link;

    .line 5
    .line 6
    invoke-virtual {v1}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->unbox-impl()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object p0, p0, Lgf0/g;->a:Lgf0/h;

    .line 11
    .line 12
    check-cast p0, Ldf0/b;

    .line 13
    .line 14
    iput-object v1, p0, Ldf0/b;->a:Ljava/lang/String;

    .line 15
    .line 16
    return-object v0
.end method
