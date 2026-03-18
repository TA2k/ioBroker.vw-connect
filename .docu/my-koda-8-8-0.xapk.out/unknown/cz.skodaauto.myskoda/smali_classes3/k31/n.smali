.class public final Lk31/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/h;


# direct methods
.method public constructor <init>(Lf31/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/n;->a:Lf31/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Li31/j;
    .locals 0

    .line 1
    iget-object p0, p0, Lk31/n;->a:Lf31/h;

    .line 2
    .line 3
    iget-object p0, p0, Lf31/h;->a:Lb31/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lb31/a;->c()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Li31/j;

    .line 10
    .line 11
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lk31/n;->a()Li31/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
