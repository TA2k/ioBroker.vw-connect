.class public final Loc0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqc0/c;
.implements Lme0/b;
.implements Lme0/a;


# instance fields
.field public final a:Lwe0/a;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Loc0/a;->a:Lwe0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Loc0/a;->a:Lwe0/a;

    .line 2
    .line 3
    check-cast p0, Lwe0/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 6
    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method
