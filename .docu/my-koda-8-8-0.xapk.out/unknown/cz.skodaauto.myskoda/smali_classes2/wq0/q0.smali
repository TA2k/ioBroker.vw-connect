.class public final Lwq0/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwq0/r;


# direct methods
.method public constructor <init>(Lwq0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/q0;->a:Lwq0/r;

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
    check-cast v1, Lyq0/k;

    .line 5
    .line 6
    iget-object v1, v1, Lyq0/k;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Lwq0/q0;->a:Lwq0/r;

    .line 9
    .line 10
    check-cast p0, Ltq0/a;

    .line 11
    .line 12
    iput-object v1, p0, Ltq0/a;->b:Ljava/lang/String;

    .line 13
    .line 14
    return-object v0
.end method
