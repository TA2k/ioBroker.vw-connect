.class public interface abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x609
    name = "StateCallback"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008`\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u0007H&\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0017\u0010\u000c\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\u0001H&\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0017\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u000f\u001a\u00020\u000eH&\u00a2\u0006\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;",
        "",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateChangeInformation;",
        "stateChangeInformation",
        "Llx0/b0;",
        "onStateChange",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateChangeInformation;)V",
        "Ll71/x;",
        "values",
        "onStateValuesChange",
        "(Ll71/x;)V",
        "sideEffect",
        "onSideEffect",
        "(Ljava/lang/Object;)V",
        "Lt71/e;",
        "safetyInstructionStatus",
        "onSafetyInstructionChange",
        "(Lt71/e;)V",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract onSafetyInstructionChange(Lt71/e;)V
.end method

.method public abstract onSideEffect(Ljava/lang/Object;)V
.end method

.method public abstract onStateChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateChangeInformation;)V
.end method

.method public abstract onStateValuesChange(Ll71/x;)V
.end method
