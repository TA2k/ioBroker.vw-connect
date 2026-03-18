.class public final Ltj/k;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lmj/a;

.field public e:Lqi/a;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

.field public h:I


# direct methods
.method public constructor <init>(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltj/k;->g:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Ltj/k;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Ltj/k;->h:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Ltj/k;->h:I

    .line 9
    .line 10
    iget-object p1, p0, Ltj/k;->g:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->clearDataAndClose(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
