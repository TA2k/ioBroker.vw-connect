.class public final Lqf0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lqf0/a;


# direct methods
.method public constructor <init>(Lqf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqf0/h;->a:Lqf0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lqf0/h;->a:Lqf0/a;

    .line 2
    .line 3
    check-cast p0, Lof0/b;

    .line 4
    .line 5
    iget-object p0, p0, Lof0/b;->a:Lve0/u;

    .line 6
    .line 7
    const-string v0, "PREF_DEMO_ENABLED"

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-virtual {p0, v0, v1}, Lve0/u;->h(Ljava/lang/String;Z)Lyy0/i;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
