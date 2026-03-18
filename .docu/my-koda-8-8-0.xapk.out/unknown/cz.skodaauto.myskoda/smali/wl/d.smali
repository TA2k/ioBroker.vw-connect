.class public final Lwl/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwl/f;


# instance fields
.field public final a:Ljl/i;

.field public final b:Ltl/i;


# direct methods
.method public constructor <init>(Ljl/i;Ltl/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwl/d;->a:Ljl/i;

    .line 5
    .line 6
    iput-object p2, p0, Lwl/d;->b:Ltl/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lwl/d;->b:Ltl/i;

    .line 2
    .line 3
    instance-of v1, v0, Ltl/n;

    .line 4
    .line 5
    iget-object p0, p0, Lwl/d;->a:Ljl/i;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    instance-of v0, v0, Ltl/d;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void
.end method
